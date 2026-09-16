rule TTP_XOR_QUAD_CurrentVersionRun_0c3c {
  strings:
    $key_0c3c = { 5f 53 [2] 7b 5d [2] 50 71 [2] 7e 53 [2] 6a 48 [2] 65 52 [2] 7b 4f [2] 79 4e [2] 62 48 [2] 7e 4f [2] 62 60 }

  condition:
    any of them
}