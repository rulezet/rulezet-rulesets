rule TTP_XOR_QUAD_CurrentVersionRun_1201 {
  strings:
    $key_1201 = { 41 6e [2] 65 60 [2] 4e 4c [2] 60 6e [2] 74 75 [2] 7b 6f [2] 65 72 [2] 67 73 [2] 7c 75 [2] 60 72 [2] 7c 5d }

  condition:
    any of them
}