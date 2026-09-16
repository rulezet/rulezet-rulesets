rule TTP_XOR_QUAD_CurrentVersionRun_e53a {
  strings:
    $key_e53a = { b6 55 [2] 92 5b [2] b9 77 [2] 97 55 [2] 83 4e [2] 8c 54 [2] 92 49 [2] 90 48 [2] 8b 4e [2] 97 49 [2] 8b 66 }

  condition:
    any of them
}