rule TTP_XOR_QUAD_CurrentVersionRun_3c10 {
  strings:
    $key_3c10 = { 6f 7f [2] 4b 71 [2] 60 5d [2] 4e 7f [2] 5a 64 [2] 55 7e [2] 4b 63 [2] 49 62 [2] 52 64 [2] 4e 63 [2] 52 4c }

  condition:
    any of them
}