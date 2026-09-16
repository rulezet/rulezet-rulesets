rule TTP_XOR_QUAD_CurrentVersionRun_273d {
  strings:
    $key_273d = { 74 52 [2] 50 5c [2] 7b 70 [2] 55 52 [2] 41 49 [2] 4e 53 [2] 50 4e [2] 52 4f [2] 49 49 [2] 55 4e [2] 49 61 }

  condition:
    any of them
}