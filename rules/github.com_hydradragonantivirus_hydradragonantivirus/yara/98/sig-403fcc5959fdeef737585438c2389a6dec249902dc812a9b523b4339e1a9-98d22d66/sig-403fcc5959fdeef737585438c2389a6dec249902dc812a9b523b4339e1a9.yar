rule sig_403fcc5959fdeef737585438c2389a6dec249902dc812a9b523b4339e1a9 {
  meta:
    description = "datamaliciousorder - file 403fcc5959fdeef737585438c2389a6dec249902dc812a9b523b4339e1a9b282.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "403fcc5959fdeef737585438c2389a6dec249902dc812a9b523b4339e1a9b282"

  strings:
    $x1  = "\"$Execute = (Get-Content -Path 'C:\\\\Users\\\\Public\\\\Execute.txt');\" +" fullword ascii
    $x2  = "\"$Invoke = (Get-Content -Path 'C:\\\\Users\\\\Public\\\\Invoke.txt');\" +" fullword ascii
    $x3  = "exec(\"powershell.exe -Command \\\"\" + src + \"\\\"\", function(err, stdout, stderr) {" fullword ascii
    $x4  = "var command = \"[<#12554656#>Reflection.Assembly<#12554656#>]::$klaat([Byte[]]$runpeD).$ype($new).$hekm($Execute).$Invoke($null," ascii
    $s5  = "var exec = require(\"child_process\").exec;" fullword ascii
    $s6  = "var command = \"[<#12554656#>Reflection.Assembly<#12554656#>]::$klaat([Byte[]]$runpeD).$ype($new).$hekm($Execute).$Invoke($null," ascii
    $s7  = "Object[]]($HJI,$null,[Byte[]]$wqi,$true)); Stop-Process -Name 'node'\";" fullword ascii
    $s8  = "\"$count = 0; for ($i = 0; $i -lt $danz.Count - 1; $i += 2)\" +" fullword ascii
    $s9  = "src += command; " fullword ascii
    $s10 = "    \"return [System.Text.Encoding]::ASCII.GetString($JS.ToArray());\" +" fullword ascii
    $s11 = "\"{ $wqi[$count] = [byte]($danz[$i]); $count++;\" +" fullword ascii
    $s12 = "var src = \"Function FH([String] $far) {\" +" fullword ascii
    $s13 = "\"return $wqi };\" +" fullword ascii
    $s14 = "\"function majs { param([string] $str)\" +" fullword ascii
    $s15 = "        \"$JS.Add([Convert]::ToByte($far.Substring($i, 8), 2));\" +" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}