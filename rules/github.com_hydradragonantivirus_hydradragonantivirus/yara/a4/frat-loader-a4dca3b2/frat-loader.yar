rule frat_loader {
  meta:
    author = "jeFF0Falltrades"
    ref    = "https://twitter.com/jeFF0Falltrades/status/1270709679375646720"

  strings:
    $str_report_0 = "$ReportDone = Get-BDE" wide ascii
    $str_report_1 = "$Report = Get-BDE" wide ascii
    $str_img_0    = "$ImgURL = Get-BDE" wide ascii
    $str_img_1    = "Write-Host 'No Image'" wide ascii
    $str_img_2    = "$goinf + \"getimageerror\"" wide ascii
    $str_link     = "$eLink = Get-BDE" wide ascii
    $str_tmp_0    = "$Shortcut.WorkingDirectory = $TemplatesFolder" wide ascii
    $str_tmp_1    = "TemplatesFolder = [Environment]::GetFolderPath" wide ascii
    $str_tmp_2    = "$vbout = $($TemplatesFolder)" wide ascii
    $str_shurtcut = "Get-Shurtcut" wide ascii
    $str_info_0   = "info=LoadFirstError" wide ascii
    $str_info_1   = "info=LoadSecondError" wide ascii
    $str_info_2   = "getimagedone?msg" wide ascii
    $str_info_3   = "donemanuel?id" wide ascii
    $str_info_4   = "getDone?msg" wide ascii
    $str_info_5   = "getManualDone?msg" wide ascii

  condition:
    3 of them
}