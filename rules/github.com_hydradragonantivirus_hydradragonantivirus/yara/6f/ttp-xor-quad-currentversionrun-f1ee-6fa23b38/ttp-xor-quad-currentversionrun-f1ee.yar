rule TTP_XOR_QUAD_CurrentVersionRun_f1ee {
  strings:
    $key_f1ee = { a2 81 [2] 86 8f [2] ad a3 [2] 83 81 [2] 97 9a [2] 98 80 [2] 86 9d [2] 84 9c [2] 9f 9a [2] 83 9d [2] 9f b2 }

  condition:
    any of them
}