rule TTP_XOR_QUAD_CurrentVersionRun_2821 {
  strings:
    $key_2821 = { 7b 4e [2] 5f 40 [2] 74 6c [2] 5a 4e [2] 4e 55 [2] 41 4f [2] 5f 52 [2] 5d 53 [2] 46 55 [2] 5a 52 [2] 46 7d }

  condition:
    any of them
}