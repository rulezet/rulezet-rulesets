rule TTP_XOR_QUAD_CurrentVersionRun_fff3 {
  strings:
    $key_fff3 = { ac 9c [2] 88 92 [2] a3 be [2] 8d 9c [2] 99 87 [2] 96 9d [2] 88 80 [2] 8a 81 [2] 91 87 [2] 8d 80 [2] 91 af }

  condition:
    any of them
}