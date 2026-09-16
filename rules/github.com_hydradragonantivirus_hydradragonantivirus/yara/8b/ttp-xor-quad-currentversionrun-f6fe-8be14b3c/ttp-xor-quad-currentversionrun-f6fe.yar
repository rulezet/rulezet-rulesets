rule TTP_XOR_QUAD_CurrentVersionRun_f6fe {
  strings:
    $key_f6fe = { a5 91 [2] 81 9f [2] aa b3 [2] 84 91 [2] 90 8a [2] 9f 90 [2] 81 8d [2] 83 8c [2] 98 8a [2] 84 8d [2] 98 a2 }

  condition:
    any of them
}