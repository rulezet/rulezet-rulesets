rule TTP_XOR_QUAD_CurrentVersionRun_ff28 {
  strings:
    $key_ff28 = { ac 47 [2] 88 49 [2] a3 65 [2] 8d 47 [2] 99 5c [2] 96 46 [2] 88 5b [2] 8a 5a [2] 91 5c [2] 8d 5b [2] 91 74 }

  condition:
    any of them
}