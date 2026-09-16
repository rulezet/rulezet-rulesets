rule TTP_XOR_QUAD_CurrentVersionRun_f2fa {
  strings:
    $key_f2fa = { a1 95 [2] 85 9b [2] ae b7 [2] 80 95 [2] 94 8e [2] 9b 94 [2] 85 89 [2] 87 88 [2] 9c 8e [2] 80 89 [2] 9c a6 }

  condition:
    any of them
}