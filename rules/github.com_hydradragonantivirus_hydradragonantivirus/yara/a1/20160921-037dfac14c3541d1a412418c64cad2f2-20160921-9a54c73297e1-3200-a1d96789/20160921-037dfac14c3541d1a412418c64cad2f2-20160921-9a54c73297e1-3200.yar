rule _20160921_037dfac14c3541d1a412418c64cad2f2_20160921_9a54c73297e1_3200 {
  meta:
    description = "datamaliciousorder - from files 20160921_037dfac14c3541d1a412418c64cad2f2.js, 20160921_9a54c73297e1211ec78765c2c1c7c05b.js, 20160921_acebc8ac4559526a5a8de801968bd19f.js, 20160922_e83e21df386eef1a99bc7a65e7e6f6f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdbf3b67df915739d64604188a4862042efa316e641ef50d228a41f9327767cc"
    hash2       = "3d2e8d0924bbdcf83eaa5ef9fde5baf8f4e12cf5c14d5f8ceb77a4c3e708abd3"
    hash3       = "79fe55ec3d2d6dbd854df9676c4565b6a8410e1d94298c2ff2f112036fcfac73"
    hash4       = "ff3bd7f3bb53e5b0bbfefd44c539b38a506a76e4dae03eaa91c64f99e34b846b"

  strings:
    $s1 = "\"GGn\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(func" ascii
    $s2 = "){return \"GGn\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do\";}" ascii
    $s3 = "Kp\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"OMd\";})(),(functio" ascii
    $s4 = "\"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(fun" ascii
    $s5 = "function f000(){return \"QDg\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yz\";})(),(function f000(){ret" ascii
    $s6 = " \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yz\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}