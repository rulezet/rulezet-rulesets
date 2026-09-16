rule TTP_XOR_WriteProcessMemory_fb8e {
  strings:
    $key_fb8e = { ac fc [2] 9e de [2] 98 eb [2] b6 eb [2] 89 f7 }

  condition:
    any of them
}