rule TTP_XOR_WriteProcessMemory_ad99 {
  strings:
    $key_ad99 = { fa eb [2] c8 c9 [2] ce fc [2] e0 fc [2] df e0 }

  condition:
    any of them
}