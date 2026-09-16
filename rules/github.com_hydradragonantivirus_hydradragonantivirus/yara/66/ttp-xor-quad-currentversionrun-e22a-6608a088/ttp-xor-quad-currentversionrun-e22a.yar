rule TTP_XOR_QUAD_CurrentVersionRun_e22a {
  strings:
    $key_e22a = { b1 45 [2] 95 4b [2] be 67 [2] 90 45 [2] 84 5e [2] 8b 44 [2] 95 59 [2] 97 58 [2] 8c 5e [2] 90 59 [2] 8c 76 }

  condition:
    any of them
}