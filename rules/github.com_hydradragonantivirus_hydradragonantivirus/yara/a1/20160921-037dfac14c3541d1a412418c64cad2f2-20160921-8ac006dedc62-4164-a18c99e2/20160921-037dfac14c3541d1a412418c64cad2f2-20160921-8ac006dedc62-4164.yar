rule _20160921_037dfac14c3541d1a412418c64cad2f2_20160921_8ac006dedc62_4164 {
  meta:
    description = "datamaliciousorder - from files 20160921_037dfac14c3541d1a412418c64cad2f2.js, 20160921_8ac006dedc6205f05757feeef6cd894a.js, 20160921_9a54c73297e1211ec78765c2c1c7c05b.js, 20160921_f1aea308b2000a8d722d0f21c756fabf.js, 20160922_e83e21df386eef1a99bc7a65e7e6f6f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdbf3b67df915739d64604188a4862042efa316e641ef50d228a41f9327767cc"
    hash2       = "00e17d6bd534b2582622ec06dbd3fa43882b34044fc369b6707b8d580a7cc293"
    hash3       = "3d2e8d0924bbdcf83eaa5ef9fde5baf8f4e12cf5c14d5f8ceb77a4c3e708abd3"
    hash4       = "3175e432bce3be89acef4ff7215de666ea47cac857c8c07ff649c1cdd5484103"
    hash5       = "ff3bd7f3bb53e5b0bbfefd44c539b38a506a76e4dae03eaa91c64f99e34b846b"

  strings:
    $s1 = "n \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(f" ascii
    $s2 = "rn \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"PTi\";})(),(" ascii
    $s3 = "(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000()" ascii
    $s4 = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"MBb\";})(),(function f000(" ascii
    $s5 = "rn \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}