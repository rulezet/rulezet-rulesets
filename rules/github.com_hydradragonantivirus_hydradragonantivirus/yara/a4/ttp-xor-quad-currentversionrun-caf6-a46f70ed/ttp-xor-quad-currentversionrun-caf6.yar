rule TTP_XOR_QUAD_CurrentVersionRun_caf6 {
  strings:
    $key_caf6 = { 99 99 [2] bd 97 [2] 96 bb [2] b8 99 [2] ac 82 [2] a3 98 [2] bd 85 [2] bf 84 [2] a4 82 [2] b8 85 [2] a4 aa }

  condition:
    any of them
}