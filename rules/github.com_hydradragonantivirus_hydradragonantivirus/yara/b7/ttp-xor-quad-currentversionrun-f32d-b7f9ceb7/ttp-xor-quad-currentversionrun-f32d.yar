rule TTP_XOR_QUAD_CurrentVersionRun_f32d {
  strings:
    $key_f32d = { a0 42 [2] 84 4c [2] af 60 [2] 81 42 [2] 95 59 [2] 9a 43 [2] 84 5e [2] 86 5f [2] 9d 59 [2] 81 5e [2] 9d 71 }

  condition:
    any of them
}