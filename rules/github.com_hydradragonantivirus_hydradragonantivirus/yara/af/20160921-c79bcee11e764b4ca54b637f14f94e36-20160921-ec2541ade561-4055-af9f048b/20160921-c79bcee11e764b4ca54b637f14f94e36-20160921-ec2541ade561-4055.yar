rule _20160921_c79bcee11e764b4ca54b637f14f94e36_20160921_ec2541ade561_4055 {
  meta:
    description = "datamaliciousorder - from files 20160921_c79bcee11e764b4ca54b637f14f94e36.js, 20160921_ec2541ade561a4750092fda52be6f269.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fdd10a2dcebc0c4099b99fb3316b9cdd6c3afd60abc1b93345fc041eb2405ec0"
    hash2       = "1db7ed5a240fde30e4fca12eca866b9b96b56836ae50ea4c0fcf2d28b08be3b5"

  strings:
    $s1 = "})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Br\";})(),(function f000" ascii
    $s2 = "on f000(){return \"Wy\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"O" ascii
    $s3 = ",(function f000(){return \"Qa\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"RVb\";})(),(function f000(){r" ascii
    $s4 = "(){return \"BQb\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Br\";}" ascii
    $s5 = "tion f000(){return \"Uo\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return " ascii
    $s6 = "eturn \"EZu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Rh\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}