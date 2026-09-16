rule TTP_XOR_QUAD_CurrentVersionRun_321d {
  strings:
    $key_321d = { 61 72 [2] 45 7c [2] 6e 50 [2] 40 72 [2] 54 69 [2] 5b 73 [2] 45 6e [2] 47 6f [2] 5c 69 [2] 40 6e [2] 5c 41 }

  condition:
    any of them
}