rule TTP_XOR_QUAD_CurrentVersionRun_fff6 {
  strings:
    $key_fff6 = { ac 99 [2] 88 97 [2] a3 bb [2] 8d 99 [2] 99 82 [2] 96 98 [2] 88 85 [2] 8a 84 [2] 91 82 [2] 8d 85 [2] 91 aa }

  condition:
    any of them
}