rule TTP_XOR_QUAD_CurrentVersionRun_353a {
  strings:
    $key_353a = { 66 55 [2] 42 5b [2] 69 77 [2] 47 55 [2] 53 4e [2] 5c 54 [2] 42 49 [2] 40 48 [2] 5b 4e [2] 47 49 [2] 5b 66 }

  condition:
    any of them
}