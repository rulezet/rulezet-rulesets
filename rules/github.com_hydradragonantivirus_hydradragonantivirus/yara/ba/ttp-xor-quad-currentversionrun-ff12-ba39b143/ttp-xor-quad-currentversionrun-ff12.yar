rule TTP_XOR_QUAD_CurrentVersionRun_ff12 {
  strings:
    $key_ff12 = { ac 7d [2] 88 73 [2] a3 5f [2] 8d 7d [2] 99 66 [2] 96 7c [2] 88 61 [2] 8a 60 [2] 91 66 [2] 8d 61 [2] 91 4e }

  condition:
    any of them
}