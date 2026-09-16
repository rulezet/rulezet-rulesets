rule TTP_XOR_WriteProcessMemory_fb39 {
  strings:
    $key_fb39 = { ac 4b [2] 9e 69 [2] 98 5c [2] b6 5c [2] 89 40 }

  condition:
    any of them
}