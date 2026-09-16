rule TTP_XOR_QUAD_CurrentVersionRun_f32f {
  strings:
    $key_f32f = { a0 40 [2] 84 4e [2] af 62 [2] 81 40 [2] 95 5b [2] 9a 41 [2] 84 5c [2] 86 5d [2] 9d 5b [2] 81 5c [2] 9d 73 }

  condition:
    any of them
}