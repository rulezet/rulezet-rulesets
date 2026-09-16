rule TTP_XOR_QUAD_CurrentVersionRun_e2fa {
  strings:
    $key_e2fa = { b1 95 [2] 95 9b [2] be b7 [2] 90 95 [2] 84 8e [2] 8b 94 [2] 95 89 [2] 97 88 [2] 8c 8e [2] 90 89 [2] 8c a6 }

  condition:
    any of them
}