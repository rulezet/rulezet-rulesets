rule TTP_XOR_QUAD_CurrentVersionRun_e22b {
  strings:
    $key_e22b = { b1 44 [2] 95 4a [2] be 66 [2] 90 44 [2] 84 5f [2] 8b 45 [2] 95 58 [2] 97 59 [2] 8c 5f [2] 90 58 [2] 8c 77 }

  condition:
    any of them
}