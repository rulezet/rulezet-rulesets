rule TTP_XOR_QUAD_CurrentVersionRun_783d {
  strings:
    $key_783d = { 2b 52 [2] 0f 5c [2] 24 70 [2] 0a 52 [2] 1e 49 [2] 11 53 [2] 0f 4e [2] 0d 4f [2] 16 49 [2] 0a 4e [2] 16 61 }

  condition:
    any of them
}