rule TTP_XOR_WriteProcessMemory_888e {
  strings:
    $key_888e = { df fc [2] ed de [2] eb eb [2] c5 eb [2] fa f7 }

  condition:
    any of them
}