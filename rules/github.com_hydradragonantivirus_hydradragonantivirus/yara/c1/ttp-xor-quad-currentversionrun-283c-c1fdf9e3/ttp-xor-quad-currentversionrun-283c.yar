rule TTP_XOR_QUAD_CurrentVersionRun_283c {
  strings:
    $key_283c = { 7b 53 [2] 5f 5d [2] 74 71 [2] 5a 53 [2] 4e 48 [2] 41 52 [2] 5f 4f [2] 5d 4e [2] 46 48 [2] 5a 4f [2] 46 60 }

  condition:
    any of them
}