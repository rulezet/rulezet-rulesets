rule TTP_XOR_QUAD_CurrentVersionRun_122d {
  strings:
    $key_122d = { 41 42 [2] 65 4c [2] 4e 60 [2] 60 42 [2] 74 59 [2] 7b 43 [2] 65 5e [2] 67 5f [2] 7c 59 [2] 60 5e [2] 7c 71 }

  condition:
    any of them
}