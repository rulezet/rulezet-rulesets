rule TTP_XOR_QUAD_CurrentVersionRun_c0cb {
  strings:
    $key_c0cb = { 93 a4 [2] b7 aa [2] 9c 86 [2] b2 a4 [2] a6 bf [2] a9 a5 [2] b7 b8 [2] b5 b9 [2] ae bf [2] b2 b8 [2] ae 97 }

  condition:
    any of them
}