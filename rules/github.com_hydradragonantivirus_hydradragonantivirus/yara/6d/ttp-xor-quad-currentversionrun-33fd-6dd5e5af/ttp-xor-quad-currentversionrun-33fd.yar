rule TTP_XOR_QUAD_CurrentVersionRun_33fd {
  strings:
    $key_33fd = { 60 92 [2] 44 9c [2] 6f b0 [2] 41 92 [2] 55 89 [2] 5a 93 [2] 44 8e [2] 46 8f [2] 5d 89 [2] 41 8e [2] 5d a1 }

  condition:
    any of them
}