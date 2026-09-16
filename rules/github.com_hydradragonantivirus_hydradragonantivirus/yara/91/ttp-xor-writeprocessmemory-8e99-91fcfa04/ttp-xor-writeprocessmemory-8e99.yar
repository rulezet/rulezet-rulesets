rule TTP_XOR_WriteProcessMemory_8e99 {
  strings:
    $key_8e99 = { d9 eb [2] eb c9 [2] ed fc [2] c3 fc [2] fc e0 }

  condition:
    any of them
}