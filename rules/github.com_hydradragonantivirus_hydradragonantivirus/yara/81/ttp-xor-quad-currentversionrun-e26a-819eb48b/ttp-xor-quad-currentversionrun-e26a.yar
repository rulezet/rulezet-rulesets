rule TTP_XOR_QUAD_CurrentVersionRun_e26a {
  strings:
    $key_e26a = { b1 05 [2] 95 0b [2] be 27 [2] 90 05 [2] 84 1e [2] 8b 04 [2] 95 19 [2] 97 18 [2] 8c 1e [2] 90 19 [2] 8c 36 }

  condition:
    any of them
}