rule TTP_XOR_QUAD_CurrentVersionRun_203a {
  strings:
    $key_203a = { 73 55 [2] 57 5b [2] 7c 77 [2] 52 55 [2] 46 4e [2] 49 54 [2] 57 49 [2] 55 48 [2] 4e 4e [2] 52 49 [2] 4e 66 }

  condition:
    any of them
}