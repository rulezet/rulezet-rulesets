rule _20160921_1de6da840ee50be73263cde38bfe05f8_20160921_86391eeb9293_4624 {
  meta:
    description = "datamaliciousorder - from files 20160921_1de6da840ee50be73263cde38bfe05f8.js, 20160921_86391eeb92939f7926213db5cee16e4d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28c58fd3e89dda2f745d131d428bf5c447e7f5e2bdee82bb72c417d8a0be878a"
    hash2       = "1238f360c84929f303678fcd3899297cac43bef18dc5a731b7a6272fde7fe4e6"

  strings:
    $s1 = " \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s2 = "000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"HJm" ascii
    $s3 = " \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"MJq\";})(),(fu" ascii
    $s4 = "rn \"Qa\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fu" ascii
    $s5 = "(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Go\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}