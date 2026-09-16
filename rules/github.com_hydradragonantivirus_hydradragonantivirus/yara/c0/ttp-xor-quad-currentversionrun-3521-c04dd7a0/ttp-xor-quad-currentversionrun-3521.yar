rule TTP_XOR_QUAD_CurrentVersionRun_3521 {
  strings:
    $key_3521 = { 66 4e [2] 42 40 [2] 69 6c [2] 47 4e [2] 53 55 [2] 5c 4f [2] 42 52 [2] 40 53 [2] 5b 55 [2] 47 52 [2] 5b 7d }

  condition:
    any of them
}