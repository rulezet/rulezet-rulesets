rule TTP_XOR_QUAD_CurrentVersionRun_aef6 {
  strings:
    $key_aef6 = { fd 99 [2] d9 97 [2] f2 bb [2] dc 99 [2] c8 82 [2] c7 98 [2] d9 85 [2] db 84 [2] c0 82 [2] dc 85 [2] c0 aa }

  condition:
    any of them
}