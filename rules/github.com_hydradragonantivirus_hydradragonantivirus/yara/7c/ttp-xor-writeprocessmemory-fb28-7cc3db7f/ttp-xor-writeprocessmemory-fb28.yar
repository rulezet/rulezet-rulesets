rule TTP_XOR_WriteProcessMemory_fb28 {
  strings:
    $key_fb28 = { ac 5a [2] 9e 78 [2] 98 4d [2] b6 4d [2] 89 51 }

  condition:
    any of them
}