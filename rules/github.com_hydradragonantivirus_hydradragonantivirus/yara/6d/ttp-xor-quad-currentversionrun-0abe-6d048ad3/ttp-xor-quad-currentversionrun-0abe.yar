rule TTP_XOR_QUAD_CurrentVersionRun_0abe {
  strings:
    $key_0abe = { 59 d1 [2] 7d df [2] 56 f3 [2] 78 d1 [2] 6c ca [2] 63 d0 [2] 7d cd [2] 7f cc [2] 64 ca [2] 78 cd [2] 64 e2 }

  condition:
    any of them
}