rule zSUSP_NTDLL_Stack_String_Padding {
  meta:
    author      = "Greg Lesnewich"
    description = "detect ntdll.dll being moved to the stack with empty padding being used to clear the register prior to use"
    date        = "2024-01-23"
    version     = "1.0"
    DaysofYARA  = "23/100"

  strings:
    $0x1d5c1369a = { 20 20 20 20 ?? 6e 74 64 6c [10-20] 20 20 20 20 ?? 6c 2e 64 6c }
                
  condition:
    all of them
}