rule TTP_XOR_QUAD_CurrentVersionRun_ff02 {
  strings:
    $key_ff02 = { ac 6d [2] 88 63 [2] a3 4f [2] 8d 6d [2] 99 76 [2] 96 6c [2] 88 71 [2] 8a 70 [2] 91 76 [2] 8d 71 [2] 91 5e }

  condition:
    any of them
}