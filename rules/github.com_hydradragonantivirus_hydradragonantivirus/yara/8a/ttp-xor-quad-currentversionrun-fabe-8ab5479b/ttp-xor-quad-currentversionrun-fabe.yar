rule TTP_XOR_QUAD_CurrentVersionRun_fabe {
  strings:
    $key_fabe = { a9 d1 [2] 8d df [2] a6 f3 [2] 88 d1 [2] 9c ca [2] 93 d0 [2] 8d cd [2] 8f cc [2] 94 ca [2] 88 cd [2] 94 e2 }

  condition:
    any of them
}