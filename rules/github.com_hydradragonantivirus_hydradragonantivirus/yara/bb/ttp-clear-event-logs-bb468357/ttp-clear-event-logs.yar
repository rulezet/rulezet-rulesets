rule TTP_clear_event_logs {
  meta:
    description   = "Matches references to 'wevtutil' or 'Clear-Eventlog' - used to clear Windows Event Logs."
    last_modified = "2024-03-14"
    author        = "@petermstewart"
    DaysofYara    = "74/100"

  strings:
    $a = "wevtutil cl" ascii wide nocase
    $b = "wevtutil.exe cl" ascii wide nocase
    $c = "wevtutil clear log" ascii wide nocase
    $d = "wevtutil.exe clear log" ascii wide nocase
    $e = "Clear-EventLog" ascii wide nocase  
  condition:
    uint16(0) == 0x5a4d and
    any of them
}