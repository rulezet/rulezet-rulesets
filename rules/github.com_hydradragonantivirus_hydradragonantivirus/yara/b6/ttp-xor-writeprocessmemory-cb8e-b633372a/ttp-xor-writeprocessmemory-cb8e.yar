rule TTP_XOR_WriteProcessMemory_cb8e {
  strings:
    $key_cb8e = { 9c fc [2] ae de [2] a8 eb [2] 86 eb [2] b9 f7 }

  condition:
    any of them
}