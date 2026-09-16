rule _20160921_523b4f49bbdc4dd92accd0e402a46bfd_20160921_61ffae07802b_3774 {
  meta:
    description = "datamaliciousorder - from files 20160921_523b4f49bbdc4dd92accd0e402a46bfd.js, 20160921_61ffae07802bf5013fbbf8f137c827c3.js, 20160921_68596411289b2d10a74a19f9fce4a325.js, 20160921_b4c84c92954782bcf19013150a359ec6.js, 20160921_be882ab89423f06a9e76ba0cb72775fe.js, 20160921_f1b8df0ab75abc0c2b3be738559f2ab3.js, 20160921_f850d4c4897a9bd959014c9fc7d18a6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f9f8d6d5ec4629c30430c47234803f947380ed84d76b2caa48ab30caee473c3"
    hash2       = "d1b5dbd3605683fd0b3b1dc802f1048401a8db23070c8205273f5c5ab6c5133c"
    hash3       = "52b104c52d9f1461833687ee9fc5da1913610266114cbc0018bf345ee135d662"
    hash4       = "deac288c0b80bcd19eff4e9a4bb55e7bdc0f08b0110094a0693c671b47cda285"
    hash5       = "fe4f2a5579ff9cbd713377a0d5f78bb0c6c30247b6f455ccdb4014a7c298c978"
    hash6       = "dfdf24fc382cd60cf8d9c01ff0bca33ee060801ad2bd963895209ac610525301"
    hash7       = "d8fc3e7e41c34088a452b3b6538d4581b58ba00503833e565b195ce374f63b54"

  strings:
    $s1 = "\"MJq\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Wy\";})(),(funct" ascii
    $s2 = " f000(){return \"Nv\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Iq" ascii
    $s3 = "(function f000(){return \"Tn\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"TKp\";})(),(function f000(){r" ascii
    $s4 = ";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"NBs\";})(),(function f00" ascii
    $s5 = "tion f000(){return \"TKp\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"UEg\";})(),(function f000(){retur" ascii
    $s6 = "turn \"Mc\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"YTp\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}