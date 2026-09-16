rule TTP_XOR_QUAD_CurrentVersionRun_f32e {
  strings:
    $key_f32e = { a0 41 [2] 84 4f [2] af 63 [2] 81 41 [2] 95 5a [2] 9a 40 [2] 84 5d [2] 86 5c [2] 9d 5a [2] 81 5d [2] 9d 72 }

  condition:
    any of them
}