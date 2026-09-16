rule TTP_XOR_QUAD_CurrentVersionRun_0810 {
  strings:
    $key_0810 = { 5b 7f [2] 7f 71 [2] 54 5d [2] 7a 7f [2] 6e 64 [2] 61 7e [2] 7f 63 [2] 7d 62 [2] 66 64 [2] 7a 63 [2] 66 4c }

  condition:
    any of them
}