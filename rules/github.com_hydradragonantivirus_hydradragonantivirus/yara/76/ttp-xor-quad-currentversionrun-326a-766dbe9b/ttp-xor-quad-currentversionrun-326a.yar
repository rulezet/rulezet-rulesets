rule TTP_XOR_QUAD_CurrentVersionRun_326a {
  strings:
    $key_326a = { 61 05 [2] 45 0b [2] 6e 27 [2] 40 05 [2] 54 1e [2] 5b 04 [2] 45 19 [2] 47 18 [2] 5c 1e [2] 40 19 [2] 5c 36 }

  condition:
    any of them
}