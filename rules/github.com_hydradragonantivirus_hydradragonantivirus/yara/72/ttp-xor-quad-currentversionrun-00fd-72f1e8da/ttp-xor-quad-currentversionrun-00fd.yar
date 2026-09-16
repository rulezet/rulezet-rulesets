rule TTP_XOR_QUAD_CurrentVersionRun_00fd {
  strings:
    $key_00fd = { 53 92 [2] 77 9c [2] 5c b0 [2] 72 92 [2] 66 89 [2] 69 93 [2] 77 8e [2] 75 8f [2] 6e 89 [2] 72 8e [2] 6e a1 }

  condition:
    any of them
}