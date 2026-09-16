rule TTP_XOR_QUAD_CurrentVersionRun_f132 {
  strings:
    $key_f132 = { a2 5d [2] 86 53 [2] ad 7f [2] 83 5d [2] 97 46 [2] 98 5c [2] 86 41 [2] 84 40 [2] 9f 46 [2] 83 41 [2] 9f 6e }

  condition:
    any of them
}